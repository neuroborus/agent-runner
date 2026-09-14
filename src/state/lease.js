import { join } from "node:path";

import {
  publishExclusiveFile,
  readOptionalPublishedText,
  removeFile,
} from "./files.js";
import {
  inspectProcessOwner,
  validateProcessIdentity,
} from "./process-owner.js";
import { assertRunId, RunStoreError } from "./validation.js";

const LEASE_FILENAME = ".lease";
const RECLAIMING_LEASE_FILENAME = ".lease-reclaiming";
const LEASE_FIELDS = new Set([
  "schemaVersion",
  "processIdentity",
  "runId",
  "token",
  "pid",
  "hostname",
  "acquiredAt",
]);

function parseJson(source, description, invalidLeaseCode) {
  try {
    return JSON.parse(source);
  } catch (cause) {
    throw new RunStoreError(`${description} contains invalid JSON.`, {
      cause,
      code: invalidLeaseCode,
    });
  }
}

function parseLease(
  source,
  expectedRunId,
  description,
  invalidLeaseCode,
  includeRunId,
) {
  const value = parseJson(source, description, invalidLeaseCode);
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new RunStoreError(`${description} must be an object.`, {
      code: invalidLeaseCode,
    });
  }
  const unknownField = Object.keys(value).find(
    (field) => !LEASE_FIELDS.has(field),
  );
  if (unknownField !== undefined) {
    throw new RunStoreError(`lease.${unknownField} is not supported.`, {
      code: invalidLeaseCode,
    });
  }

  try {
    if (includeRunId) assertRunId(value.runId);
    else if (value.runId !== undefined) throw new Error("Unexpected run ID");
    if (value.schemaVersion !== undefined) {
      if (value.schemaVersion !== 2)
        throw new Error("Unsupported lease version");
      validateProcessIdentity(value.processIdentity);
    } else if (value.processIdentity !== undefined) {
      throw new Error("Legacy lease identity is invalid");
    }
    assertRunId(value.token);
  } catch (cause) {
    throw new RunStoreError(`${description} identity is invalid.`, {
      cause,
      code: invalidLeaseCode,
    });
  }
  const acquiredAt = new Date(value.acquiredAt);
  if (
    (expectedRunId !== null && value.runId !== expectedRunId) ||
    !Number.isSafeInteger(value.pid) ||
    value.pid < 1 ||
    typeof value.hostname !== "string" ||
    value.hostname.length === 0 ||
    value.hostname.length > 255 ||
    /[\p{Cc}\p{Zl}\p{Zp}]/u.test(value.hostname) ||
    Number.isNaN(acquiredAt.valueOf()) ||
    acquiredAt.toISOString() !== value.acquiredAt
  ) {
    throw new RunStoreError(`${description} is invalid.`, {
      code: invalidLeaseCode,
    });
  }

  return value;
}

async function readLease(
  filePath,
  expectedRunId,
  description,
  invalidLeaseCode,
  includeRunId,
) {
  const source = await readOptionalPublishedText(filePath);
  return source === null
    ? null
    : parseLease(
        source,
        expectedRunId,
        description,
        invalidLeaseCode,
        includeRunId,
      );
}

export function createLeaseManager({
  activeLeaseDescription = "Execution lease",
  includeRunId = true,
  leaseFilename = LEASE_FILENAME,
  reclaimingFilename = RECLAIMING_LEASE_FILENAME,
  processIdentity,
  canReclaim = async () => true,
  withMutation = async (_record, operation) => operation(),
  beforeRelease = async () => {},
  conflictCode = "ERR_RUN_LEASED",
  currentDate,
  hostName,
  invalidLeaseCode = "ERR_INVALID_RUN_LEASE",
  leaseDescription = "Run lease",
  leaseSubject = (runId) => `Run ${runId}`,
  processId,
  processIsAlive,
  onPublicationBoundary,
  reclaimingLeaseDescription = "Reclaiming lease",
  requireMatchingRunId = true,
  staleMs,
  timestamp,
  tokenFactory,
}) {
  const activeLeases = new WeakMap();
  const activeLeaseName =
    `${activeLeaseDescription[0].toLowerCase()}` +
    activeLeaseDescription.slice(1);

  const mutate = (record, directory, operation) =>
    withMutation(record, operation, directory);

  function expectedRunId(runId) {
    return requireMatchingRunId ? runId : null;
  }

  function readManagedLease(filePath, runId, description = leaseDescription) {
    return readLease(
      filePath,
      expectedRunId(runId),
      description,
      invalidLeaseCode,
      includeRunId,
    );
  }

  const inspectOwner = (record) =>
    inspectProcessOwner(record, {
      hostName,
      processIsAlive,
      processIdentity,
    });

  async function leaseIsStale(lease) {
    const age = currentDate().valueOf() - Date.parse(lease.acquiredAt);
    if (age < staleMs || lease.hostname !== hostName) {
      return false;
    }
    return ["dead", "replaced"].includes(await inspectOwner(lease));
  }

  function createLeaseHandle(runDirectory, record) {
    let lease;
    lease = Object.freeze({
      runId: record.runId,
      release: () => release(lease),
    });
    activeLeases.set(lease, {
      busy: false,
      record,
      released: false,
      runDirectory,
    });
    return lease;
  }

  async function createLeaseRecord(runId) {
    const token = tokenFactory();
    assertRunId(token);
    return {
      schemaVersion: 2,
      processIdentity: validateProcessIdentity(
        await processIdentity(processId),
      ),
      ...(includeRunId ? { runId } : {}),
      token,
      pid: processId,
      hostname: hostName,
      acquiredAt: timestamp(),
    };
  }

  async function writeLeaseFile(filePath, record) {
    await publishExclusiveFile(filePath, `${JSON.stringify(record)}\n`, {
      onPublicationBoundary,
    });
  }

  async function createLeaseFile(runDirectory, runId) {
    const record = await createLeaseRecord(runId);
    await writeLeaseFile(join(runDirectory, leaseFilename), record);
    return createLeaseHandle(runDirectory, record);
  }

  async function removeOwnedMarker(runDirectory, runId, token) {
    const markerPath = join(runDirectory, reclaimingFilename);
    const marker = await readManagedLease(
      markerPath,
      runId,
      reclaimingLeaseDescription,
    );
    if (marker?.token === token) {
      await removeFile(markerPath);
    }
  }

  async function clearRecoverableMarker(runDirectory, runId) {
    const markerPath = join(runDirectory, reclaimingFilename);
    const marker = await readManagedLease(
      markerPath,
      runId,
      reclaimingLeaseDescription,
    );
    if (marker === null) {
      return null;
    }
    if (!(await leaseIsStale(marker)) || !(await canReclaim(marker, runId))) {
      throw new RunStoreError(
        `${leaseSubject(runId)} lease recovery is active.`,
        { code: conflictCode },
      );
    }
    return mutate(marker, runDirectory, async () => {
      const current = await readManagedLease(markerPath, runId);
      if (current?.token !== marker.token) return null;
      if (
        !(await leaseIsStale(current)) ||
        !(await canReclaim(current, runId))
      ) {
        throw new RunStoreError(
          `${leaseSubject(runId)} lease recovery is active.`,
          { code: conflictCode },
        );
      }
      const lease = await readManagedLease(
        join(runDirectory, leaseFilename),
        runId,
      );
      if (
        lease !== null &&
        lease.runId !== current.runId &&
        !(await canReclaim(current, null))
      ) {
        throw new RunStoreError(
          `${leaseSubject(runId)} is reserved for reconciliation.`,
          { code: conflictCode },
        );
      }
      // A crash can leave only the reclaiming record. Recheck the request and
      // publish replacement ownership before removing that last reservation.
      const recovered =
        lease === null ? await createLeaseFile(runDirectory, runId) : null;
      await removeOwnedMarker(runDirectory, runId, current.token);
      return recovered;
    });
  }

  async function acquire(runDirectory, runId) {
    const leasePath = join(runDirectory, leaseFilename);
    const markerPath = join(runDirectory, reclaimingFilename);

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const recovered = await clearRecoverableMarker(runDirectory, runId);
      if (recovered !== null) return recovered;
      try {
        const acquired = await createLeaseFile(runDirectory, runId);
        const marker = await readManagedLease(markerPath, runId);
        if (marker !== null && !(await canReclaim(marker, runId))) {
          await acquired.release();
          throw new RunStoreError(
            `${leaseSubject(runId)} is reserved for reconciliation.`,
            { code: conflictCode },
          );
        }
        return acquired;
      } catch (cause) {
        if (cause?.code !== "EEXIST") {
          throw cause;
        }
      }

      const existingLease = await readManagedLease(leasePath, runId);
      if (existingLease === null) {
        continue;
      }
      if (
        !(await leaseIsStale(existingLease)) ||
        !(await canReclaim(existingLease, runId))
      ) {
        throw new RunStoreError(`${leaseSubject(runId)} is already leased.`, {
          code: conflictCode,
        });
      }

      const reclaimingLease = await createLeaseRecord(runId);
      try {
        await writeLeaseFile(markerPath, reclaimingLease);
      } catch (cause) {
        if (cause?.code === "EEXIST") {
          continue;
        }
        throw cause;
      }

      try {
        const acquired = await mutate(existingLease, runDirectory, async () => {
          const currentLease = await readManagedLease(leasePath, runId);
          if (currentLease?.token !== existingLease.token) return null;
          if (
            !(await leaseIsStale(currentLease)) ||
            !(await canReclaim(currentLease, runId))
          ) {
            throw new RunStoreError(
              `${leaseSubject(runId)} is already leased.`,
              { code: conflictCode },
            );
          }
          await removeFile(leasePath);
          try {
            return await createLeaseFile(runDirectory, runId);
          } catch (cause) {
            // Preserve the old reservation when replacement publication fails.
            try {
              await writeLeaseFile(leasePath, currentLease);
            } catch (restoreCause) {
              if (restoreCause?.code !== "EEXIST") throw restoreCause;
            }
            throw cause;
          }
        });
        if (acquired !== null) return acquired;
      } catch (cause) {
        if (cause?.code === "EEXIST") {
          throw new RunStoreError(`${leaseSubject(runId)} is already leased.`, {
            cause,
            code: conflictCode,
          });
        }
        throw cause;
      } finally {
        const replacement = await readManagedLease(leasePath, runId);
        if (
          replacement?.runId === reclaimingLease.runId ||
          (await canReclaim(reclaimingLease, null))
        ) {
          await removeOwnedMarker(runDirectory, runId, reclaimingLease.token);
        }
      }
    }

    throw new RunStoreError(
      `${leaseSubject(runId)} lease could not be acquired.`,
      { code: conflictCode },
    );
  }

  async function owner(runDirectory, runId) {
    const lease = await readManagedLease(
      join(runDirectory, leaseFilename),
      runId,
    );
    if (lease === null) {
      const marker = await readManagedLease(
        join(runDirectory, reclaimingFilename),
        runId,
      );
      return marker !== null && !(await canReclaim(marker, null))
        ? marker.runId
        : null;
    }
    return lease !== null &&
      (!(await leaseIsStale(lease)) || !(await canReclaim(lease, null)))
      ? lease.runId
      : null;
  }

  async function isLeased(runDirectory, runId) {
    return (await owner(runDirectory, runId)) !== null;
  }

  async function ownerIsLive(runDirectory, runId) {
    const lease = await readManagedLease(
      join(runDirectory, leaseFilename),
      runId,
    );
    return (
      lease !== null &&
      !["dead", "replaced"].includes(await inspectOwner(lease))
    );
  }

  async function assertLeaseFile(metadata) {
    const persistedLease = await readManagedLease(
      join(metadata.runDirectory, leaseFilename),
      metadata.record.runId,
    );
    if (persistedLease?.token !== metadata.record.token) {
      throw new RunStoreError(`${activeLeaseDescription} is no longer owned.`, {
        code: invalidLeaseCode,
      });
    }
  }

  async function runExclusive(lease, operation) {
    const metadata = activeLeases.get(lease);
    if (metadata === undefined || metadata.released) {
      throw new RunStoreError(`A current ${activeLeaseName} is required.`, {
        code: invalidLeaseCode,
      });
    }
    if (metadata.busy) {
      throw new RunStoreError(
        `${activeLeaseDescription} already has an active write.`,
        { code: "ERR_RUN_LEASE_BUSY" },
      );
    }

    metadata.busy = true;
    try {
      return await mutate(metadata.record, metadata.runDirectory, async () => {
        await assertLeaseFile(metadata);
        return operation(metadata);
      });
    } finally {
      metadata.busy = false;
    }
  }

  async function release(lease) {
    const metadata = activeLeases.get(lease);
    if (metadata === undefined || metadata.released) {
      return;
    }
    if (metadata.busy) {
      throw new RunStoreError(`Cannot release a busy ${activeLeaseName}.`, {
        code: "ERR_RUN_LEASE_BUSY",
      });
    }

    await mutate(metadata.record, metadata.runDirectory, async () => {
      await assertLeaseFile(metadata);
      await beforeRelease(metadata.record);
      await removeFile(join(metadata.runDirectory, leaseFilename));
      metadata.released = true;
    });
  }

  async function inspect(runDirectory, runId) {
    const record = await readManagedLease(
      join(runDirectory, leaseFilename),
      runId,
    );
    return record === null
      ? null
      : Object.freeze({ ...record, status: await inspectOwner(record) });
  }

  return Object.freeze({
    acquire,
    inspect,
    isLeased,
    owner,
    ownerIsLive,
    runExclusive,
  });
}
