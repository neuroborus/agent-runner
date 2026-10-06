import { constants } from "node:fs";
import { open, readFile, readlink, realpath, lstat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { readProcessIdentity } from "../../../src/agents/index.js";
import {
  normalizeLinuxReceipt,
  sameLinuxIdentity,
  assessLinuxRetirement,
} from "./protocol.js";
import {
  normalizeLinuxFileControl,
  assertLinuxFileControlPolicy,
} from "./files-protocol.js";

export const digest = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");

/** Effective kernel credentials include potential capability elevation and
 * supplementary groups, not just the current effective capability mask. */
export function linuxKernelAuthority(status, details) {
  const number = (value) => {
    const result = Number(value);
    if (
      value === undefined ||
      !Number.isSafeInteger(result) ||
      result < 0 ||
      result > 2147483647
    )
      throw new Error("Unverifiable kernel credentials");
    return result;
  };
  const credentials = (name) => {
    const values = status.match(
      new RegExp(
        `^${name}:[ \\t]+([0-9]+)[ \\t]+([0-9]+)[ \\t]+([0-9]+)[ \\t]+([0-9]+)$`,
        "mu",
      ),
    );
    if (!values) throw new Error("Unverifiable kernel credentials");
    return Object.fromEntries(
      ["real", "effective", "saved", "filesystem"].map((kind, index) => [
        kind,
        number(values[index + 1]),
      ]),
    );
  };
  const uids = credentials("Uid"),
    gids = credentials("Gid");
  const uid = uids.effective,
    gid = gids.effective;
  const groups = status.match(/^Groups:[ \t]*([0-9 \t]*)$/mu)?.[1];
  if (groups === undefined || Buffer.byteLength(status) > 65536)
    throw new Error("Unverifiable kernel groups");
  const capabilitySets = Object.fromEntries(
    ["Inh", "Prm", "Eff", "Bnd", "Amb"].map((name) => {
      const value = status.match(
        new RegExp(`^Cap${name}:\\s+([a-f0-9]{16})$`, "mu"),
      )?.[1];
      if (!value) throw new Error("Unverifiable kernel capabilities");
      return [name, value];
    }),
  );
  const noNewPrivileges = number(status.match(/^NoNewPrivs:\s+([01])$/mu)?.[1]);
  const seccomp = number(status.match(/^Seccomp:\s+([012])$/mu)?.[1]);
  return {
    uid,
    gid,
    uids,
    gids,
    groups: groups
      .trim()
      .split(/\s+/u)
      .filter(Boolean)
      .map((value) => ({ gid: number(value) })),
    capabilities: capabilitySets.Eff,
    capabilitySets,
    noNewPrivileges,
    seccomp,
    sessionId: details.session,
    identitySha256: digest(JSON.stringify(details.identity)),
  };
}

export async function processDetails(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0)
    throw new Error("Invalid process identity");
  const before = await readProcessIdentity(pid);
  if (before === null) throw new Error("Inaccessible process identity");
  const base = `/proc/${pid}`;
  const [stat, status, namespaceId, networkId, ipcId, mountId] =
    await Promise.all([
      readFile(`${base}/stat`, "utf8"),
      readFile(`${base}/status`, "utf8"),
      readlink(`${base}/ns/pid`),
      readlink(`${base}/ns/net`),
      readlink(`${base}/ns/ipc`),
      readlink(`${base}/ns/mnt`),
    ]);
  const fields = stat
    .slice(stat.lastIndexOf(")") + 2)
    .trim()
    .split(/\s+/u);
  const nspid = status
    .match(/^NSpid:\s+([0-9\s]+)$/mu)?.[1]
    .trim()
    .split(/\s+/u)
    .map(Number);
  const after = await readProcessIdentity(pid);
  if (
    !sameLinuxIdentity(before, after) ||
    fields[19] !== before.startTicks ||
    !nspid?.length
  )
    throw new Error("Unstable process identity");
  return {
    pid,
    identity: before,
    namespaceId,
    networkId,
    ipcId,
    mountId,
    nspid,
    parent: Number(fields[1]),
    session: Number(fields[3]),
  };
}

export async function inspectFixtureMounts(
  pid,
  fixture,
  output,
  fs = { readFile, lstat },
) {
  const fileHelper = fixture.fileHelper === true;
  const control = fileHelper
    ? normalizeLinuxFileControl(fixture.fileControl ?? null)
    : null;
  if (control !== null) assertLinuxFileControlPolicy(fixture.policy, control);
  const table = await fs.readFile(`/proc/${pid}/mountinfo`, "utf8");
  if (Buffer.byteLength(table) > 65536)
    throw new Error("Oversized fixture mount table");
  const decode = (value) =>
    value.replace(/\\([0-7]{3})/gu, (_, octal) =>
      String.fromCharCode(parseInt(octal, 8)),
    );
  const mounts = table
    .trim()
    .split("\n")
    .map((line) => {
      const fields = line.split(" ");
      const separator = fields.indexOf("-");
      if (separator < 6) throw new Error("Unverifiable fixture mount");
      return {
        target: decode(fields[4]),
        options: fields[5].split(","),
        filesystem: fields[separator + 1],
      };
    });
  const inputs = fileHelper
    ? [
        ["/proof/bin/file-helper", fixture.executable],
        ["/anchor", output],
        ...(control === "mount"
          ? [["/anchor/crossing", `${output}/.crossing-source`]]
          : []),
      ]
    : [
        ["/proof/bin/node", fixture.executable],
        ["/proof/payload.cjs", fixture.payload],
        ...fixture.policy.libraries.map(({ target, source }) => [
          target,
          source,
        ]),
        ...(fixture.policy.grants ?? []).map(({ target, source }) => [
          target,
          source,
        ]),
      ];
  const allowed = new Set(
    fileHelper
      ? [
          "/",
          ...inputs.map(([target]) => target),
          ...(control === "magic-link" ? ["/proc"] : []),
        ]
      : [
          "/",
          "/output",
          "/proc",
          "/dev",
          "/dev/pts",
          "/dev/shm",
          ...["null", "zero", "full", "random", "urandom", "tty"].map(
            (name) => `/dev/${name}`,
          ),
          ...inputs.map(([target]) => target),
        ],
  );
  if (
    mounts.some(({ target }) => !allowed.has(target)) ||
    new Set(mounts.map(({ target }) => target)).size !== mounts.length ||
    mounts.find(({ target }) => target === "/")?.filesystem !== "tmpfs"
  )
    throw new Error("Unexpected host filesystem authority");
  for (const [target, source] of [
    ...inputs,
    ...(fileHelper ? [] : [["/output", output]]),
  ]) {
    const mount = mounts.find((entry) => entry.target === target);
    const writable = fileHelper
      ? target === "/anchor"
      : target === "/output" ||
        fixture.policy.grants?.find((entry) => entry.target === target)
          ?.writable;
    if (!mount || !mount.options.includes(writable ? "rw" : "ro"))
      throw new Error("Incorrect fixture mount authority");
    const [inside, outside] = await Promise.all([
      fs.lstat(`/proc/${pid}/root${target}`, { bigint: true }),
      fs.lstat(source, { bigint: true }),
    ]);
    if (inside.ino !== outside.ino || inside.dev !== outside.dev)
      throw new Error("Substituted fixture mount source");
  }
  if (
    (!fileHelper || control === "magic-link") &&
    mounts.find(({ target }) => target === "/proc")?.filesystem !== "proc"
  )
    throw new Error("Missing private procfs");
}

/** Bounded immutable owner evidence; callers validate its specific contract. */
export async function readProtectedEvidence(
  file,
  { fs = { realpath, open, lstat }, ownerUid = process.getuid } = {},
) {
  if ((await fs.realpath(file)) !== file)
    throw new Error("Substituted receipt path");
  const handle = await fs.open(
    file,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = await handle.stat({ bigint: true });
    if (
      !stat.isFile() ||
      stat.nlink !== 1n ||
      stat.uid !== BigInt(ownerUid()) ||
      (stat.mode & 0o7777n) !== 0o400n ||
      stat.size <= 0n ||
      stat.size > 1048576n
    )
      throw new Error("Unprotected receipt");
    const bytes = Buffer.alloc(Number(stat.size) + 1);
    let size = 0;
    while (size < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        size,
        bytes.length - size,
        size,
      );
      if (!bytesRead) break;
      size += bytesRead;
    }
    if (size !== Number(stat.size))
      throw new Error("Substituted receipt bytes");
    const after = await handle.stat({ bigint: true }),
      current = await fs.lstat(file, { bigint: true });
    if (
      !current.isFile() ||
      [
        "dev",
        "ino",
        "size",
        "mode",
        "nlink",
        "uid",
        "gid",
        "mtimeNs",
        "ctimeNs",
      ].some((key) => stat[key] !== after[key] || stat[key] !== current[key])
    )
      throw new Error("Substituted receipt identity");
    return bytes.subarray(0, size);
  } finally {
    await handle.close();
  }
}

export async function protectedReceipt(file, expectedDigest, options) {
  const bytes = await readProtectedEvidence(file, options);
  if (digest(bytes) !== expectedDigest)
    throw new Error("Substituted receipt bytes");
  return normalizeLinuxReceipt(JSON.parse(bytes));
}

async function kernelIdentity(pid, fs) {
  try {
    const [bootId, stat] = await Promise.all([
      fs.readFile("/proc/sys/kernel/random/boot_id", "utf8"),
      fs.readFile(`/proc/${pid}/stat`, "utf8"),
    ]);
    const startTicks = stat
      .slice(stat.lastIndexOf(")") + 2)
      .trim()
      .split(/\s+/u)[19];
    if (
      Buffer.byteLength(stat) > 65536 ||
      Number(stat.slice(0, stat.indexOf(" "))) !== pid ||
      !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(bootId.trim()) ||
      !/^[0-9]{1,32}$/u.test(startTicks)
    )
      throw new Error("Unverifiable process creation identity");
    return { bootId: bootId.trim(), startTicks };
  } catch (error) {
    if (["ENOENT", "ESRCH", "EACCES", "EPERM"].includes(error.code))
      return null;
    throw error;
  }
}

async function procControl(receipt, fs, pid) {
  const [
    bootId,
    observerNamespaceId,
    initNamespaceId,
    selfStat,
    self,
    init,
    table,
  ] = await Promise.all([
    fs.readFile("/proc/sys/kernel/random/boot_id", "utf8"),
    fs.readlink("/proc/self/ns/pid"),
    fs.readlink("/proc/1/ns/pid"),
    fs.readFile("/proc/self/stat", "utf8"),
    kernelIdentity(pid, fs),
    kernelIdentity(1, fs),
    fs.readFile("/proc/self/mountinfo", "utf8"),
  ]);
  if (Buffer.byteLength(table) > 65536)
    throw new Error("Unverifiable procfs visibility");
  const mounts = table
    .trim()
    .split("\n")
    .map((line) => line.split(" "));
  const proc = mounts.filter((fields) => fields[4] === "/proc");
  const mount = proc[0];
  const separator = mount?.indexOf("-");
  const fullProc =
    proc.length === 1 &&
    mount[3] === "/" &&
    separator >= 6 &&
    mount[separator + 1] === "proc" &&
    ![mount[5], mount[separator + 3]].some((options) =>
      options
        .split(",")
        .some(
          (option) =>
            option.startsWith("hidepid=") &&
            !["hidepid=0", "hidepid=off"].includes(option),
        ),
    ) &&
    !mounts.some((fields) => /^\/proc\/[0-9]+(?:\/|$)/u.test(fields[4]));
  const selfFields = selfStat
    .slice(selfStat.lastIndexOf(")") + 2)
    .trim()
    .split(/\s+/u);
  return {
    bootId: bootId.trim(),
    observerNamespaceId,
    procVisible:
      fullProc &&
      initNamespaceId === observerNamespaceId &&
      Number(selfStat.slice(0, selfStat.indexOf(" "))) === pid &&
      self !== null &&
      selfFields[19] === self.startTicks &&
      init !== null &&
      self.bootId === bootId.trim() &&
      init.bootId === bootId.trim() &&
      receipt.init.identity.bootId === bootId.trim(),
  };
}

export async function assertLinuxProcVisibility() {
  const identity = await readProcessIdentity(process.pid);
  if (
    identity === null ||
    !(
      await procControl(
        { init: { identity } },
        { readFile, readlink },
        process.pid,
      )
    ).procVisible
  )
    throw new Error("Missing full same-boot procfs retirement visibility");
}

async function processState(record, namespaceId, fs) {
  // A null identity conflates missing and inaccessible. Only
  // a separately observed proc-directory ENOENT/ESRCH can establish absence.
  const identity = await kernelIdentity(record.pid, fs);
  try {
    await fs.lstat(`/proc/${record.pid}`);
  } catch (error) {
    if (["ENOENT", "ESRCH"].includes(error.code) && identity === null)
      return "absent";
    return "inaccessible";
  }
  if (identity === null) return "inaccessible";
  if (!sameLinuxIdentity(identity, record.identity)) return "replaced";
  try {
    return (await fs.readlink(`/proc/${record.pid}/ns/pid`)) === namespaceId
      ? "live"
      : "mismatched";
  } catch {
    return "inaccessible";
  }
}

async function receiptState(receipt, fs) {
  const states = await Promise.all([
    processState(receipt.init, receipt.init.namespaceId, fs),
    processState(receipt.launcher, receipt.parentNamespaceId, fs),
    processState(receipt.controller, receipt.parentNamespaceId, fs),
  ]);
  return (
    ["replaced", "mismatched", "inaccessible", "live"].find((state) =>
      states.includes(state),
    ) ?? "absent"
  );
}

/** Fresh verifier: observes only, never signals. PID-namespace init retirement
 * kills every member (including nested namespaces). No zombie/null shortcut. */
export async function verifyLinuxRetirement(
  file,
  expectedDigest,
  {
    fs = { readFile, readlink, lstat, realpath, open },
    ownerUid = process.getuid,
    pid = process.pid,
  } = {},
) {
  try {
    const receipt = await protectedReceipt(file, expectedDigest, {
      fs,
      ownerUid,
    });
    const beforeControl = await procControl(receipt, fs, pid);
    const deadline = performance.now() + 3000;
    let before;
    do {
      before = await receiptState(receipt, fs);
      if (before !== "live") break;
      // Bounded retirement observation, not fault ordering or retry-until-green.
      await new Promise((resolve) => setTimeout(resolve, 20));
    } while (performance.now() < deadline);
    const control = await procControl(receipt, fs, pid);
    const after = await receiptState(receipt, fs);
    const afterControl = await procControl(receipt, fs, pid);
    await protectedReceipt(file, expectedDigest, { fs, ownerUid });
    const procVisible = [beforeControl, control, afterControl].every(
      (entry) =>
        entry.procVisible &&
        entry.bootId === control.bootId &&
        entry.observerNamespaceId === control.observerNamespaceId,
    );
    return assessLinuxRetirement(receipt, {
      ...control,
      procVisible,
      before,
      after,
    });
  } catch {
    return { status: "RETAINED", independent: false, emergencyCleanup: false };
  }
}

export async function descendants(initPid) {
  const pending = [initPid];
  const seen = new Set(pending);
  const result = [];
  while (pending.length) {
    const pid = pending.shift();
    const text = await readFile(`/proc/${pid}/task/${pid}/children`, "utf8");
    for (const child of text.trim().split(/\s+/u).filter(Boolean).map(Number)) {
      if (
        !Number.isSafeInteger(child) ||
        child <= 0 ||
        seen.has(child) ||
        seen.size >= 64
      )
        throw new Error("Ambiguous namespace membership");
      seen.add(child);
      result.push(await processDetails(child));
      pending.push(child);
    }
  }
  return result;
}
