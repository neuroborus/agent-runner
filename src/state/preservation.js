import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, realpath } from "node:fs/promises";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  atomicWriteFile,
  openRegularFile,
  readStableText,
  syncDirectory,
} from "./files.js";
import { assertRunId, deepFreeze, preservationError } from "./validation.js";

const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const identity = (stat) => ({
  device: String(stat.dev),
  inode: String(stat.ino),
});
function fail() {
  throw preservationError();
}

async function directoryIdentity(path, expected = null) {
  const stat = await lstat(path, { bigint: true });
  const actual = identity(stat);
  if (
    !stat.isDirectory() ||
    stat.uid !== BigInt(process.getuid()) ||
    (stat.mode & 0o777n) !== 0o700n ||
    (await realpath(path)) !== path ||
    (expected !== null && !isDeepStrictEqual(actual, expected))
  )
    fail();
  return actual;
}

async function withDirectory(path, expected, operation) {
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    if (
      !isDeepStrictEqual(
        identity(await handle.stat({ bigint: true })),
        expected,
      )
    )
      fail();
    await directoryIdentity(path, expected);
    const result = await operation(`/proc/self/fd/${handle.fd}`);
    await directoryIdentity(path, expected);
    return result;
  } finally {
    await handle.close();
  }
}

async function readJson(path, expectedHash = null, expectedIdentity = null) {
  try {
    const before = await lstat(path, { bigint: true });
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      before.uid !== BigInt(process.getuid()) ||
      (before.mode & 0o777n) !== 0o600n
    )
      fail();
    if (
      expectedIdentity !== null &&
      !isDeepStrictEqual(identity(before), expectedIdentity)
    )
      fail();
    const source = await readStableText(path, MAX_MANIFEST_BYTES);
    const after = await lstat(path, { bigint: true });
    if (
      !isDeepStrictEqual(identity(before), identity(after)) ||
      (expectedHash !== null && digest(source) !== expectedHash)
    )
      fail();
    return JSON.parse(source);
  } catch (cause) {
    throw preservationError(cause);
  }
}

async function writeJson(path, value) {
  const source = JSON.stringify(value) + "\n";
  if (Buffer.byteLength(source) > MAX_MANIFEST_BYTES) fail();
  await atomicWriteFile(path, source);
  return digest(source);
}

function protectedPaths(state) {
  return [
    state.taskPath,
    ...(state.projectConfigurationProtection
      ? [state.projectConfigurationProtection.path]
      : []),
  ];
}

// Separate from executionResource: no cancellation or transient cleanup path
// owns these bytes. The phase files form a write-ahead preservation journal.
export function createPreservationStore({
  withLease,
  getRunDirectory,
  loadRun,
  onBoundary,
}) {
  // Only small immutable record references enter state JSON. Each publication is
  // journaled before it can authorize capture progress or a destructive write.
  async function readRecord(runDirectory, state, id) {
    assertRunId(id);
    const reference = state.preservationRecords.find(
      (entry) => entry.id === id,
    );
    if (!reference) return null;
    return readJson(
      join(runDirectory, `.preservation-record-${reference.fileId}.json`),
      reference.hash,
      reference.identity,
    );
  }

  async function persistRecord(session, id, record) {
    const fileId = randomUUID();
    const path = join(
      session.runDirectory,
      `.preservation-record-${fileId}.json`,
    );
    const hash = await writeJson(path, record);
    const reference = {
      id,
      fileId,
      hash,
      identity: identity(await lstat(path, { bigint: true })),
    };
    await readJson(path, hash, reference.identity);
    await session.publish(reference);
    return reference;
  }

  async function load(runDirectory, state, id) {
    const record = await readRecord(runDirectory, state, id);
    const reference = state.preservationRecords.find(
      (entry) => entry.id === id,
    );
    if (
      !record ||
      record.kind !== "capture" ||
      record.schemaVersion !== 1 ||
      record.runId !== state.runId ||
      record.preservationId !== id ||
      Object.keys(record).sort().join() !==
        "binding,directoryId,identity,kind,preservationId,ready,runId,schemaVersion" ||
      !record.binding ||
      Object.keys(record.binding).sort().join() !== "revision,snapshot" ||
      !Number.isSafeInteger(record.binding.revision) ||
      record.binding.revision < 1 ||
      record.binding.snapshot?.projectPath !== state.projectPath ||
      (record.directoryId === null) !== (record.identity === null) ||
      (record.directoryId === null && record.ready !== null)
    )
      fail();
    if (record.directoryId === null)
      return { record, path: null, runDirectory, reference };
    assertRunId(record.directoryId);
    const path = join(runDirectory, `.preservation-${record.directoryId}`);
    await directoryIdentity(path, record.identity);
    return { path, record, runDirectory, reference };
  }

  function blobs(path, descriptors, expectedIdentity) {
    return {
      async write(entry, bytes) {
        if (digest(bytes) !== entry.hash || bytes.length !== entry.size) fail();
        if (Object.hasOwn(descriptors, entry.hash)) return;
        await withDirectory(path, expectedIdentity, async (root) => {
          const blobPath = join(root, entry.hash);
          await atomicWriteFile(blobPath, bytes);
          descriptors[entry.hash] = {
            identity: identity(await lstat(blobPath, { bigint: true })),
            size: bytes.length,
          };
        });
      },
      async read(entry) {
        if (!/^[a-f0-9]{64}$/u.test(entry.hash)) fail();
        const saved = descriptors[entry.hash];
        if (!saved || saved.size !== entry.size) fail();
        return withDirectory(path, expectedIdentity, async (root) => {
          const blobPath = join(root, entry.hash);
          const handle = await openRegularFile(blobPath, constants.O_RDONLY);
          try {
            const before = await handle.stat({ bigint: true });
            if (
              !isDeepStrictEqual(identity(before), saved.identity) ||
              before.uid !== BigInt(process.getuid()) ||
              (before.mode & 0o777n) !== 0o600n ||
              before.size !== BigInt(saved.size)
            )
              fail();
            const bytes = await handle.readFile();
            const after = await handle.stat({ bigint: true });
            const named = await lstat(blobPath, { bigint: true });
            if (
              !isDeepStrictEqual(identity(named), saved.identity) ||
              named.nlink !== 1n ||
              named.ctimeNs !== after.ctimeNs ||
              before.mtimeNs !== after.mtimeNs ||
              before.ctimeNs !== after.ctimeNs ||
              digest(bytes) !== entry.hash ||
              bytes.length !== entry.size
            )
              fail();
            return bytes;
          } finally {
            await handle.close();
          }
        });
      },
    };
  }

  async function verified(saved) {
    async function assertRecordUnchanged() {
      const { runDirectory, reference } = saved;
      await readJson(
        join(runDirectory, `.preservation-record-${reference.fileId}.json`),
        reference.hash,
        reference.identity,
      );
    }
    await assertRecordUnchanged();
    const { ready } = saved.record;
    if (
      !ready ||
      Object.keys(ready).sort().join() !==
        "identity,manifestHash,manifestIdentity,payloadId" ||
      typeof ready.payloadId !== "string" ||
      !/^[a-f0-9]{64}$/u.test(ready.manifestHash)
    )
      fail();
    assertRunId(ready.payloadId);
    const path = join(saved.path, ready.payloadId);
    await directoryIdentity(path, ready.identity);
    const manifestPath = join(path, "manifest.json");
    const manifestStat = await lstat(manifestPath, { bigint: true });
    if (!isDeepStrictEqual(identity(manifestStat), ready.manifestIdentity))
      fail();
    const payload = await withDirectory(path, ready.identity, (root) =>
      readJson(join(root, "manifest.json"), ready.manifestHash),
    );
    if (
      !payload ||
      Object.keys(payload).sort().join() !== "blobs,manifest" ||
      !payload.blobs ||
      !payload.manifest ||
      !Array.isArray(payload.manifest.entries) ||
      payload.manifest.projectPath !==
        saved.record.binding.snapshot.projectPath ||
      payload.manifest.baseHead !== saved.record.binding.snapshot.head ||
      payload.manifest.contentFingerprint !==
        saved.record.binding.snapshot.contentFingerprint
    )
      fail();
    async function assertManifestUnchanged() {
      const current = await lstat(manifestPath, { bigint: true }).catch(
        (cause) => {
          if (cause.code !== "ENOENT") throw cause;
          return null;
        },
      );
      if (
        current === null ||
        [
          "dev",
          "ino",
          "mode",
          "uid",
          "gid",
          "nlink",
          "size",
          "mtimeNs",
          "ctimeNs",
        ].some((key) => manifestStat[key] !== current[key])
      )
        fail();
    }
    const payloadBlobs = blobs(path, payload.blobs, ready.identity);
    const storage = {
      read: (entry) =>
        withDirectory(saved.path, saved.record.identity, async () => {
          await assertRecordUnchanged();
          await assertManifestUnchanged();
          const bytes = await payloadBlobs.read(entry);
          await assertManifestUnchanged();
          await assertRecordUnchanged();
          return bytes;
        }),
    };
    for (const pair of payload.manifest.entries) {
      if (!pair?.before || !pair.after) fail();
      for (const entry of [pair.before, pair.after])
        if (entry.kind !== "deleted") await storage.read(entry);
    }
    await directoryIdentity(saved.path, saved.record.identity);
    await directoryIdentity(path, ready.identity);
    await assertManifestUnchanged();
    await assertRecordUnchanged();
    return { manifest: payload.manifest, storage };
  }

  async function capture(
    lease,
    {
      preservationId,
      expectedRevision,
      expectedSnapshot,
      worktreeLease,
      git,
      signal,
    },
  ) {
    return withLease(lease, worktreeLease, async (session) => {
      const { runDirectory, state } = session;
      assertRunId(preservationId);
      const binding = {
        revision: expectedRevision,
        snapshot: expectedSnapshot,
      };
      let saved;
      if (state.preservationRecords.some(({ id }) => id === preservationId)) {
        saved = await load(runDirectory, state, preservationId);
        if (!isDeepStrictEqual(saved.record.binding, binding)) fail();
      } else {
        if (
          state.revision !== expectedRevision ||
          expectedSnapshot?.projectPath !== state.projectPath
        )
          fail();
        await git.assertUnchanged(expectedSnapshot);
        saved = {
          path: null,
          runDirectory,
          record: {
            schemaVersion: 1,
            kind: "capture",
            runId: state.runId,
            preservationId,
            binding,
            directoryId: null,
            identity: null,
            ready: null,
          },
        };
        saved.reference = await persistRecord(
          session,
          preservationId,
          saved.record,
        );
      }
      if (saved.record.ready === null) {
        await onBoundary({ phase: "capture-intent", preservationId });
        signal?.throwIfAborted();
        if (saved.path === null) {
          const directoryId = randomUUID();
          const path = join(runDirectory, `.preservation-${directoryId}`);
          await mkdir(path, { mode: 0o700 });
          await syncDirectory(runDirectory);
          const record = {
            ...saved.record,
            directoryId,
            identity: await directoryIdentity(path),
          };
          const reference = await persistRecord(
            session,
            preservationId,
            record,
          );
          saved = { path, record, runDirectory, reference };
          await onBoundary({ phase: "storage-allocated", preservationId });
        }

        // Each interrupted capture retains its owned attempt; never adopt partial storage.
        const payloadId = randomUUID();
        const path = join(saved.path, payloadId);
        await withDirectory(saved.path, saved.record.identity, (root) =>
          mkdir(join(root, payloadId), { mode: 0o700 }),
        );
        const payloadIdentity = await directoryIdentity(path);
        const descriptors = {};
        const storage = blobs(path, descriptors, payloadIdentity);
        const manifest = await git.captureChanges({
          expectedSnapshot,
          writeBlob: storage.write,
          signal,
          protectedPaths: protectedPaths(state),
        });
        const manifestHash = await withDirectory(
          path,
          payloadIdentity,
          (root) =>
            writeJson(join(root, "manifest.json"), {
              manifest,
              blobs: descriptors,
            }),
        );
        await directoryIdentity(path, payloadIdentity);
        const record = {
          ...saved.record,
          ready: {
            payloadId,
            identity: payloadIdentity,
            manifestHash,
            manifestIdentity: identity(
              await lstat(join(path, "manifest.json"), { bigint: true }),
            ),
          },
        };
        // Read back every saved byte before publishing authority for removal.
        await verified({ ...saved, record });
        await directoryIdentity(saved.path, saved.record.identity);
        await syncDirectory(saved.path);
        saved.reference = await persistRecord(session, preservationId, record);
        saved.record = record;
        await onBoundary({ phase: "captured", preservationId });
      }
      await verified(saved);
      return deepFreeze(structuredClone(saved.record));
    });
  }

  async function restore(
    lease,
    {
      preservationId,
      operationId,
      expectedSnapshot,
      paths,
      target,
      worktreeLease,
      git,
      signal,
    },
  ) {
    assertRunId(operationId);
    return withLease(lease, worktreeLease, async (session) => {
      const { runDirectory, state } = session;
      const saved = await load(runDirectory, state, preservationId);
      const { manifest, storage } = await verified(saved);
      const request = { expectedSnapshot, paths, target };
      let intent = await readRecord(runDirectory, state, operationId);
      if (intent === null) {
        if (
          expectedSnapshot?.projectPath !== state.projectPath ||
          operationId === preservationId
        )
          fail();
        const operation = await git.prepareRestoration({
          manifest,
          expectedSnapshot,
          paths,
          target,
          protectedPaths: protectedPaths(state),
        });
        intent = {
          schemaVersion: 1,
          kind: "restore",
          preservationId,
          request,
          operation,
          prepared: {},
          complete: false,
          result: null,
        };
        await persistRecord(session, operationId, intent);
      }
      if (
        intent.schemaVersion !== 1 ||
        intent.kind !== "restore" ||
        intent.preservationId !== preservationId ||
        Object.keys(intent).sort().join() !==
          "complete,kind,operation,prepared,preservationId,request,result,schemaVersion" ||
        !isDeepStrictEqual(intent.request, request) ||
        typeof intent.complete !== "boolean" ||
        !intent.prepared ||
        !isDeepStrictEqual(intent.operation?.snapshot, expectedSnapshot)
      )
        fail();
      if (intent.complete)
        return deepFreeze({
          preservationId,
          operationId,
          complete: true,
          result: intent.result,
        });
      await onBoundary({
        phase: "restore-intent",
        preservationId,
        operationId,
      });
      const result = await git.applyRestoration({
        operation: intent.operation,
        operationId,
        signal,
        readBlob: storage.read,
        readPrepared: (index) => intent.prepared[index] ?? null,
        async recordPrepared(index, preparedEntry) {
          intent = {
            ...intent,
            prepared: { ...intent.prepared, [index]: preparedEntry },
          };
          await persistRecord(session, operationId, intent);
          await onBoundary({
            phase: preparedEntry.ready
              ? "path-prepared"
              : preparedEntry.identity === null
                ? "path-preparing"
                : "path-created",
            preservationId,
            operationId,
            index,
          });
        },
        onApplied: (index) =>
          onBoundary({
            phase: "path-applied",
            preservationId,
            operationId,
            index,
          }),
      });
      await verified(saved);
      intent = { ...intent, complete: true, result };
      await persistRecord(session, operationId, intent);
      await onBoundary({ phase: "restored", preservationId, operationId });
      return deepFreeze({
        preservationId,
        operationId,
        complete: true,
        result,
      });
    });
  }

  async function read(runId, preservationId) {
    const saved = await load(
      await getRunDirectory(runId),
      await loadRun(runId),
      preservationId,
    );
    if (saved.record.ready !== null) await verified(saved);
    return deepFreeze(structuredClone(saved.record));
  }
  return Object.freeze({ capture, restore, read });
}
