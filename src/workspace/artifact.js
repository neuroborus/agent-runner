import { createHash } from "node:crypto";
import { once } from "node:events";
import { constants } from "node:fs";
import { basename, dirname, join } from "node:path";
import { Worker } from "node:worker_threads";

import {
  assertBindings,
  assertSafe,
  identity,
  observation,
  openDirectory,
  same,
  WorkspaceSafetyError,
} from "./paths.js";

const MAX_BYTES = 32 * 1024 * 1024;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fileIdentity = (stat) => ({
  ...identity(stat),
  birthtimeNs: String(stat.birthtimeNs),
});
const REPORT_CHANGED = "ERR_WORKSPACE_REPORT_CHANGED";
const TEMPORARY_CONFLICT = "ERR_WORKSPACE_REPORT_TEMPORARY_CONFLICT";
// The isolated worker holds libuv out of its poll loop from watch registration
// through the closing sample. An inotify read then observes queued events
// directly, independent of callback ordering.
const OBSERVER = `
const { parentPort, workerData } = require("node:worker_threads");
const {
  readFileSync, readdirSync, readlinkSync, readSync, statSync, watch,
} = require("node:fs");
const { path, destination, temporary, closing } = workerData;
const markerPath = "/proc/thread-self";
const { dev, ino } = statSync(markerPath, { bigint: true });
// Decode Linux stat's packed device number. fdinfo prints the kernel device
// number with the major above the 20-bit minor.
const major = (dev >> 8n) & 0xfffn;
const minor = (dev & 0xffn) | ((dev >> 12n) & 0xfff00n);
const device = (major << 20n) | minor;
const markerIdentity = " ino:" + ino.toString(16) + " sdev:" + device.toString(16) + " ";
// Descriptors are shared across threads. A watch on this thread's own proc
// directory identifies its queue even if another worker watches the same parent.
const marker = watch(markerPath);
const queues = [];
for (const fd of readdirSync("/proc/self/fd")) {
  try {
    if (readlinkSync("/proc/self/fd/" + fd) !== "anon_inode:inotify") continue;
    const info = readFileSync("/proc/self/fdinfo/" + fd, "utf8");
    if (info.includes(markerIdentity)) queues.push(Number(fd));
  } catch (cause) {
    if (cause.code !== "ENOENT") throw cause;
  }
}
if (queues.length !== 1) throw new Error("Report readback queue is unavailable.");
const watcher = watch(path);
parentPort.postMessage(null);
Atomics.wait(closing, 0, 0);

function collect(fd) {
  const buffer = Buffer.alloc(4096);
  const fields = new Uint32Array(buffer.buffer, buffer.byteOffset, buffer.length / 4);
  const destinationName = Buffer.from(destination);
  const temporaryName = Buffer.from(temporary);
  let changed = false;
  let sawDestination = false;
  let sawTemporary = false;
  // Bound collection even if writers keep filling the nonblocking queue.
  for (let batch = 0; batch < 16; batch++) {
    let bytes;
    try {
      bytes = readSync(fd, buffer);
    } catch (cause) {
      if (cause.code !== "EAGAIN") throw cause;
      return { changed, temporaryOnly: sawTemporary && !sawDestination };
    }
    for (let offset = 0; offset < bytes; ) {
      // Linux inotify_event has four 32-bit fields followed by its padded name.
      const length = fields[offset / 4 + 3];
      const start = offset + 16;
      const name = buffer.subarray(start, start + length);
      const end = name.indexOf(0);
      const filename = end < 0 ? name : name.subarray(0, end);
      changed = true;
      // Nameless events include overflow and loss of the watched directory.
      if (length === 0 || filename.equals(destinationName)) sawDestination = true;
      if (filename.equals(temporaryName)) sawTemporary = true;
      offset = start + length;
    }
  }
  return { changed: true, temporaryOnly: false };
}
try {
  parentPort.postMessage(collect(queues[0]));
} finally {
  watcher.close();
  marker.close();
}
`;

async function observeDirectory(path, destination, temporary) {
  const closing = new Int32Array(
    new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT),
  );
  const worker = new Worker(OBSERVER, {
    eval: true,
    workerData: { path, destination, temporary, closing },
    execArgv: [],
    env: {},
  });
  const stopped = new Promise((_resolve, reject) => {
    worker.once("error", reject);
    worker.once("exit", () =>
      reject(new Error("Report readback observer stopped.")),
    );
  });
  stopped.catch(() => {});
  const message = async () =>
    (await Promise.race([once(worker, "message"), stopped]))[0];
  try {
    await message();
  } catch (cause) {
    await worker.terminate();
    throw cause;
  }
  return {
    collect: () => {
      const result = message();
      Atomics.store(closing, 0, 1);
      Atomics.notify(closing, 0);
      return result;
    },
    close: () => worker.terminate(),
  };
}

export async function readArtifact(fs, path, code = REPORT_CHANGED, lookup) {
  const statAtPath = lookup ?? (() => fs.lstat(path, { bigint: true }));
  let handle;
  try {
    handle = await fs.open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = await handle.stat({ bigint: true });
    // For publication, a regular file that lost every link goes through the
    // guarded path lookup before the file-safety check.
    if (lookup && before.isFile() && before.nlink === 0n) {
      await lookup();
      assertSafe(false, "Report artifact changed during inspection.", code);
    }
    assertSafe(
      before.isFile() &&
        before.nlink === 1n &&
        before.size <= BigInt(MAX_BYTES),
      "Report artifact must be an isolated bounded regular file.",
    );
    const digest = createHash("sha256");
    const buffer = Buffer.alloc(65536);
    let size = 0;
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      size += bytesRead;
      assertSafe(
        BigInt(size) <= before.size && size <= MAX_BYTES,
        "Report artifact grew during inspection.",
        code,
      );
      digest.update(buffer.subarray(0, bytesRead));
    }
    assertSafe(
      BigInt(size) === before.size &&
        same(
          observation(before),
          observation(await handle.stat({ bigint: true })),
        ) &&
        same(observation(before), observation(await statAtPath())),
      "Report artifact changed during inspection.",
      code,
    );
    return {
      contentHash: digest.digest("hex"),
      identity: fileIdentity(before),
    };
  } catch (cause) {
    if (cause?.code === "ENOENT" && handle === undefined) return null;
    throw cause;
  } finally {
    await handle?.close();
  }
}

/** Runner-only replacement of an explicitly declared artifact, anchored to its parent. */
export async function reportArtifact(
  fs,
  inspection,
  request,
  {
    inspectOnly = false,
    temporary: owned = null,
    recordTemporary,
    assertCurrent,
    includeIdentity = false,
    assertAuthorized,
  } = {},
) {
  const { path, temporaryPath, content, expectedHash } = request;
  assertSafe(
    inspection.artifactPaths.includes(path) &&
      inspection.artifactPaths.includes(temporaryPath) &&
      path !== temporaryPath &&
      dirname(path) === dirname(temporaryPath),
    "Report paths must be exact declared artifacts.",
  );
  if (!inspectOnly)
    assertSafe(
      typeof content === "string" &&
        Buffer.byteLength(content) <= MAX_BYTES &&
        typeof recordTemporary === "function" &&
        (expectedHash === null || /^[a-f0-9]{64}$/u.test(expectedHash)),
      "Invalid report publication.",
    );
  const parent = await openDirectory(fs, dirname(path));
  const target = join(parent.anchor, basename(path));
  const temporary = join(parent.anchor, basename(temporaryPath));
  const guard = async () => {
    await assertAuthorized?.();
    await assertBindings(fs, inspection.bindings);
    assertSafe(
      (await fs.realpath(parent.anchor)) === dirname(path),
      "Report parent changed.",
      "ERR_WORKSPACE_DRIFT",
    );
  };
  // Translate only native races at the specific entry operations. Descriptor
  // failures stay generic; the outer refusal path checks for drift first.
  const entryRace = async (action, nativeCode, code = TEMPORARY_CONFLICT) => {
    try {
      return await action();
    } catch (cause) {
      if (cause?.code !== nativeCode) throw cause;
      throw new WorkspaceSafetyError(
        code === TEMPORARY_CONFLICT
          ? "Report temporary custody changed."
          : "Report destination changed during inspection.",
        { code, cause },
      );
    }
  };
  // Initial absence is an observation; only the post-open path lookup proves
  // that an opened file vanished, unlike descriptor failures.
  const targetStat = () =>
    entryRace(
      () => fs.lstat(target, { bigint: true }),
      "ENOENT",
      REPORT_CHANGED,
    );
  const readDestination = (lookup = targetStat) =>
    readArtifact(fs, target, REPORT_CHANGED, lookup);
  const readTemporary = () =>
    readArtifact(fs, temporary, TEMPORARY_CONFLICT, () =>
      entryRace(() => fs.lstat(temporary, { bigint: true }), "ENOENT"),
    );
  let observer = null;
  try {
    await guard();
    const current = await readDestination();
    await assertCurrent?.(current);
    if (inspectOnly) {
      assertSafe(
        (await readTemporary()) === null,
        "Unexpected report temporary exists.",
        TEMPORARY_CONFLICT,
      );
      await guard();
      return { path, contentHash: current?.contentHash ?? null };
    }
    const desired = hash(content);
    const currentHash = current?.contentHash ?? null;
    let publishedIdentity = current?.identity;
    assertSafe(
      currentHash === expectedHash || currentHash === desired,
      "Report artifact changed outside Runner publication.",
      REPORT_CHANGED,
    );
    let leftover = await readTemporary();
    const exact =
      owned !== null &&
      leftover !== null &&
      same(leftover.identity, owned.identity);
    if (currentHash !== desired) {
      // Write only from the expected baseline, into a temporary this run owns.
      assertSafe(
        owned === null
          ? leftover === null
          : exact &&
              (owned.phase === "writing" || leftover.contentHash === desired),
        "Report publication temporary custody cannot be proved.",
        TEMPORARY_CONFLICT,
      );
      if (owned?.phase !== "prepared") {
        // Allocate exclusively, or reopen the exact owned allocation in place.
        const handle = await entryRace(
          () =>
            fs.open(
              temporary,
              leftover === null
                ? "wx"
                : constants.O_WRONLY |
                    constants.O_NOFOLLOW |
                    constants.O_NONBLOCK,
              0o600,
            ),
          leftover === null ? "EEXIST" : "ENOENT",
        );
        try {
          const stat = await handle.stat({ bigint: true });
          const temporaryIdentity = fileIdentity(stat);
          assertSafe(
            stat.isFile() &&
              stat.nlink === 1n &&
              (leftover === null || same(temporaryIdentity, owned.identity)),
            "Report temporary ownership changed.",
            TEMPORARY_CONFLICT,
          );
          // Journal ownership before bytes can become incomplete. Reopen without
          // truncation on recovery, then verify ownership before rewriting.
          await parent.handle.sync();
          await recordTemporary({
            phase: "writing",
            identity: temporaryIdentity,
          });
          await guard();
          const atPath = await entryRace(
            () => fs.lstat(temporary, { bigint: true }),
            "ENOENT",
          );
          assertSafe(
            atPath.isFile() &&
              atPath.nlink === 1n &&
              same(fileIdentity(atPath), temporaryIdentity),
            "Report temporary was replaced before writing.",
            TEMPORARY_CONFLICT,
          );
          await handle.truncate(0);
          await handle.writeFile(content);
          await handle.sync();
          leftover = await readTemporary();
          assertSafe(
            leftover?.contentHash === desired &&
              same(leftover.identity, temporaryIdentity),
            "Written report temporary changed.",
            TEMPORARY_CONFLICT,
          );
          await recordTemporary({
            phase: "prepared",
            identity: temporaryIdentity,
          });
        } finally {
          await handle.close();
        }
      }
      await guard();
      assertSafe(
        same(await readDestination(), current),
        "Report destination changed before publication.",
        REPORT_CHANGED,
      );
      assertSafe(
        same(await readTemporary(), leftover),
        "Report temporary changed before publication.",
        TEMPORARY_CONFLICT,
      );
      publishedIdentity = leftover.identity;
      await fs.rename(temporary, target);
    } else {
      // Desired bytes already present: accept only an inert baseline or the
      // recorded prepared allocation renamed into place. Never remove files.
      assertSafe(
        leftover === null &&
          (owned === null
            ? expectedHash === desired
            : owned.phase === "prepared" &&
              same(current.identity, owned.identity)),
        "Report publication custody cannot be proved.",
        TEMPORARY_CONFLICT,
      );
    }
    await parent.handle.sync();
    await guard();
    // Compare complete entry observations, not only identity and bytes: a
    // directory-entry change of the accepted inode alters its change time or
    // links, so equal observations bound one stable readback interval.
    const destination = async () => {
      let entry = null;
      const file = await readDestination(async () => {
        entry = await targetStat();
        return entry;
      });
      return file && { ...file, entry: observation(entry) };
    };
    // Equal stat samples cannot exclude entry changes within one timestamp
    // tick, so kernel notifications for the parent bind the readback interval.
    // Any closing notification refuses the receipt; an observer that cannot
    // start or fails refuses it generically.
    observer = await observeDirectory(
      parent.anchor,
      basename(path),
      basename(temporaryPath),
    );
    // The pinned parent's own observation also brackets every readback lookup.
    const directory = async () =>
      observation(await parent.handle.stat({ bigint: true }));
    const opened = await directory();
    const published = await destination();
    assertSafe(
      published?.contentHash === desired &&
        same(published.identity, publishedIdentity),
      "Report publication readback failed.",
      REPORT_CHANGED,
    );
    // Bracket each temporary absence observation, including the one after the
    // destination reread, within that stable destination interval.
    const temporaryAbsent = async () =>
      assertSafe(
        (await readTemporary()) === null,
        "Report temporary exists after publication.",
        TEMPORARY_CONFLICT,
      );
    const destinationUnchanged = async () =>
      assertSafe(
        same(await destination(), published),
        "Report destination changed during readback.",
        REPORT_CHANGED,
      );
    await temporaryAbsent();
    await destinationUnchanged();
    await temporaryAbsent();
    await destinationUnchanged();
    const closed = await directory();
    // Linux directory iteration takes the pinned parent's inode lock, so a
    // fresh read waits for entry mutations that still have notifications to
    // queue. One batch suffices because the entries themselves are irrelevant.
    try {
      const stream = await fs.opendir(parent.anchor, { bufferSize: 1 });
      try {
        await stream.read();
      } finally {
        await stream.close();
      }
    } catch (cause) {
      await guard();
      throw cause;
    }
    const { changed, temporaryOnly } = await observer.collect();
    if (changed || !same(closed, opened)) {
      // Classify a closing change with drift first, then custody, then bytes.
      // A notification for the temporary alone stays a custody conflict.
      await guard();
      await temporaryAbsent();
      await destinationUnchanged();
      assertSafe(
        false,
        "Report directory changed during readback.",
        temporaryOnly ? TEMPORARY_CONFLICT : REPORT_CHANGED,
      );
    }
    await guard();
    return {
      path,
      contentHash: desired,
      ...(includeIdentity ? { identity: published.identity } : {}),
    };
  } catch (cause) {
    if (cause?.code === TEMPORARY_CONFLICT || cause?.code === REPORT_CHANGED)
      await guard();
    throw cause;
  } finally {
    try {
      await observer?.close();
    } finally {
      await parent.handle.close();
    }
  }
}
