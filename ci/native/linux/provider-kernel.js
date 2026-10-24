import { constants } from "node:fs";
import * as filesystem from "node:fs/promises";
import path from "node:path";
import { spawnOwnedProcess } from "../../../src/agents/index.js";
import { observationDigest, requireObservation } from "../index.js";
import { linuxKernelAuthority } from "./inspect.js";

const stable = [
  "dev",
  "ino",
  "uid",
  "gid",
  "mode",
  "nlink",
  "size",
  "mtimeNs",
  "ctimeNs",
];
export const linuxFileIdentity = (stat) =>
  Object.fromEntries(stable.map((key) => [key, String(stat[key])]));
export const sameLinuxData = (a, b) =>
  observationDigest(a) === observationDigest(b);
export const linuxProviderRootArguments = (...command) => [
  "-n",
  "--",
  "/usr/bin/env",
  "-i",
  "PATH=/usr/bin:/bin",
  "LANG=C",
  "CI=true",
  "GITHUB_ACTIONS=true",
  ...command,
];

/** Raw filesystem/process edges only. Namespace and creation identities come
 * from kernel files, never from a provider, a supplied proof or a PID label. */
export function createLinuxProviderKernel(options = {}) {
  const fs = options.fs ?? filesystem,
    spawn = options.spawn ?? spawnOwnedProcess,
    handles = new Set(),
    namespaces = new Set(),
    workers = new Set();
  let accepting = true;
  const admit = (signal) => requireObservation(accepting && !signal?.aborted);
  const text = async (file, maximum = 65536) => {
    const bytes = await fs.readFile(file);
    requireObservation(bytes.length > 0 && bytes.length <= maximum);
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  };
  const process = async (pid) => {
    requireObservation(Number.isSafeInteger(pid) && pid > 0);
    const base = `/proc/${pid}`,
      bootId = (await text("/proc/sys/kernel/random/boot_id")).trim();
    requireObservation(/^[a-f0-9-]{36}$/u.test(bootId));
    const before = await text(base + "/stat"),
      status = await text(base + "/status"),
      fields = before
        .slice(before.lastIndexOf(")") + 2)
        .trim()
        .split(/\s+/u),
      namespaces = {};
    for (const name of ["pid", "net", "ipc", "mnt", "user"])
      namespaces[name] = await fs.readlink(base + "/ns/" + name);
    const after = await text(base + "/stat"),
      fresh = after
        .slice(after.lastIndexOf(")") + 2)
        .trim()
        .split(/\s+/u);
    requireObservation(
      [1, 3, 19].every((index) => fields[index] === fresh[index]) &&
        /^[1-9][0-9]*$/u.test(fields[19]),
    );
    const nspid = status
      .match(/^NSpid:\s+([0-9 \t]+)$/mu)?.[1]
      .trim()
      .split(/\s+/u)
      .map(Number);
    requireObservation(
      nspid?.length &&
        nspid.every((value) => Number.isSafeInteger(value) && value > 0),
    );
    const value = {
      pid,
      identity: { bootId, startTicks: fields[19] },
      namespaceId: namespaces.pid,
      networkId: namespaces.net,
      ipcId: namespaces.ipc,
      mountId: namespaces.mnt,
      userId: namespaces.user,
      nspid,
      parent: Number(fields[1]),
      session: Number(fields[3]),
    };
    return { ...value, authority: linuxKernelAuthority(status, value) };
  };
  const processes = async () => {
    // A hidden procfs inventory cannot establish absence or descendant closure.
    const mounts = await text("/proc/self/mountinfo", 1048576);
    requireObservation(!/\bhidepid=[1-9]/u.test(mounts));
    const names = await fs.readdir("/proc");
    requireObservation(
      names.length <= 65536 &&
        names.includes("1") &&
        names.includes(String(options.pid ?? globalThis.process.pid)),
    );
    const values = [];
    for (const name of names.filter((name) => /^[1-9][0-9]*$/u.test(name))) {
      try {
        values.push(await process(Number(name)));
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
    }
    return values;
  };
  const hold = async (file, { directory = false, sealed = true } = {}) => {
    requireObservation(
      path.isAbsolute(file) &&
        path.normalize(file) === file &&
        (await fs.realpath(file)) === file,
    );
    for (let parent = path.dirname(file); ; parent = path.dirname(parent)) {
      const stat = await fs.lstat(parent, { bigint: true });
      requireObservation(
        (await fs.realpath(parent)) === parent &&
          stat.isDirectory() &&
          !(stat.mode & 0o22n),
      );
      if (parent === "/") break;
    }
    const handle = await fs.open(
      file,
      constants.O_RDONLY |
        constants.O_NOFOLLOW |
        constants.O_NONBLOCK |
        (directory ? constants.O_DIRECTORY : 0),
    );
    const value = { file, handle, directory, sealed, closed: false };
    handles.add(value);
    try {
      value.identity = linuxFileIdentity(await handle.stat({ bigint: true }));
      await inspect(value);
      return value;
    } catch (error) {
      await close(value);
      throw error;
    }
  };
  const inspect = async (value) => {
    requireObservation(handles.has(value) && !value.closed);
    const stat = await value.handle.stat({ bigint: true }),
      named = await fs.lstat(value.file, { bigint: true });
    requireObservation(
      (value.directory
        ? stat.isDirectory() && named.isDirectory()
        : stat.isFile() && named.isFile() && stat.nlink === 1n) &&
        !(stat.mode & 0o6022n) &&
        (!value.sealed ||
          sameLinuxData(linuxFileIdentity(stat), value.identity)) &&
        stat.dev === named.dev &&
        stat.ino === named.ino &&
        stat.mode === named.mode &&
        stat.uid === named.uid,
    );
    return linuxFileIdentity(stat);
  };
  const read = async (value, maximum = 134217728) => {
    await inspect(value);
    const before = await value.handle.stat({ bigint: true });
    requireObservation(
      !value.directory && before.size >= 0n && before.size <= BigInt(maximum),
    );
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const part = await value.handle.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (!part.bytesRead) break;
      offset += part.bytesRead;
    }
    requireObservation(
      offset === Number(before.size) &&
        sameLinuxData(linuxFileIdentity(before), await inspect(value)),
    );
    return bytes.subarray(0, offset);
  };
  const close = async (value) => {
    if (value.closed) return;
    await value.handle.close();
    await requireClosed(value.handle);
    value.closed = true;
    handles.delete(value);
  };
  const requireClosed = async (handle) => {
    try {
      await handle.stat();
    } catch (error) {
      requireObservation(error.code === "EBADF");
      return;
    }
    throw new Error("Linux provider descriptor remains open");
  };
  const namespace = async (identity) => {
    const before = await process(identity.pid);
    requireObservation(sameLinuxData(before.identity, identity.identity));
    const result = {};
    try {
      for (const name of ["pid", "net", "ipc", "mnt", "user"]) {
        const file = `/proc/${identity.pid}/ns/${name}`,
          handle = await fs.open(file, constants.O_RDONLY);
        const value = { handle };
        namespaces.add(value);
        result[name] = value;
        const stat = await handle.stat({ bigint: true }),
          label = await fs.readlink(file);
        requireObservation(label === `${name}:[${stat.ino}]`);
        Object.assign(value, { identity: `${stat.dev}:${stat.ino}`, label });
      }
      requireObservation(
        sameLinuxData(
          (await process(identity.pid)).identity,
          identity.identity,
        ),
      );
    } catch (error) {
      for (const value of Object.values(result)) await closeNamespace(value);
      throw error;
    }
    return result;
  };
  const closeNamespace = async (value) => {
    requireObservation(namespaces.has(value));
    await value.handle.close();
    await requireClosed(value.handle);
    namespaces.delete(value);
  };
  const start = (file, args, settings) => {
    admit(settings.signal);
    const worker = {
      file,
      args,
      controller: new AbortController(),
      identity: null,
      child: null,
    };
    let born,
      rejectBirth,
      admitted = false;
    worker.started = new Promise((resolve, reject) => {
      born = resolve;
      rejectBirth = reject;
    });
    worker.started.catch(() => {});
    workers.add(worker);
    const onProcess = settings.onProcess;
    const signal = AbortSignal.any([
      worker.controller.signal,
      ...(settings.signal ? [settings.signal] : []),
    ]);
    worker.child = spawn(file, args, {
      ...settings,
      signal,
      async onProcess(pid, admission) {
        // The supervisor's deregistration callback is cleanup, not admission.
        if (pid === null) {
          await onProcess?.(pid, admission);
          return;
        }
        admit(signal);
        worker.identity = await process(pid);
        const owner = await process(options.pid ?? globalThis.process.pid);
        requireObservation(
          sameLinuxData(worker.identity.identity, admission.processIdentity) &&
            worker.identity.namespaceId === admission.namespaceId &&
            worker.identity.nspid.at(-1) === 1 &&
            worker.identity.namespaceId !== owner.namespaceId,
        );
        await settings.persist?.({
          phase: "worker-created",
          file,
          args,
          identity: worker.identity,
          admission,
        });
        admit(signal);
        await onProcess?.(pid, admission);
        admit(signal);
        admitted = true;
        born(worker.identity);
      },
    });
    worker.child.ownedCompletion.catch(rejectBirth);
    worker.child.ownedCompletion.then(
      () => {
        if (!admitted)
          rejectBirth(new Error("Provider worker has no creation receipt"));
      },
      () => {},
    );
    return worker;
  };
  const absent = async (identity, namespaces = null) => {
    const all = await processes();
    requireObservation(
      !all.some((item) => item.pid === identity.pid) &&
        (!namespaces ||
          !all.some((item) => item.namespaceId === namespaces.pid.label)),
    );
    return observationDigest({
      identity,
      namespaces: namespaces
        ? Object.fromEntries(
            Object.entries(namespaces).map(([key, item]) => [
              key,
              item.identity,
            ]),
          )
        : null,
      inventory: all,
    });
  };
  const retire = async (worker) => {
    requireObservation(workers.has(worker) && worker.identity);
    worker.controller.abort();
    await worker.child.ownedCompletion;
    return absent(worker.identity, {
      pid: {
        label: worker.identity.namespaceId,
        identity: worker.identity.namespaceId,
      },
    });
  };
  return {
    fs,
    text,
    process,
    processes,
    hold,
    inspect,
    read,
    close,
    namespace,
    closeNamespace,
    start,
    fence() {
      accepting = false;
      for (const worker of workers) {
        // Revoke parked private release/probe pipes before retirement. Even a
        // continuation already queued by its caller cannot release late work.
        worker.child?.stdio[4]?.destroy();
        worker.child?.stdio[6]?.destroy();
      }
    },
    absent,
    retire,
    handles,
    namespaces,
    workers,
  };
}
