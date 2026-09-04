import { join } from "node:path";

import {
  publishExclusiveFile,
  readOptionalPublishedText,
  removeFile,
} from "./state-files.js";
import { assertRunId, RunStoreError } from "./state-validation.js";

const LEASE_FILENAME = ".lease";
const RECLAIMING_LEASE_FILENAME = ".lease-reclaiming";
const LEASE_FIELDS = new Set([
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

function parseLease(source, expectedRunId, description, invalidLeaseCode) {
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
    assertRunId(value.runId);
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
) {
  const source = await readOptionalPublishedText(filePath);
  return source === null
    ? null
    : parseLease(source, expectedRunId, description, invalidLeaseCode);
}

export function createLeaseManager({
  activeLeaseDescription = "Execution lease",
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

  function expectedRunId(runId) {
    return requireMatchingRunId ? runId : null;
  }

  function readManagedLease(filePath, runId, description = leaseDescription) {
    return readLease(
      filePath,
      expectedRunId(runId),
      description,
      invalidLeaseCode,
    );
  }

  async function ownerProcessIsAlive(lease) {
    const processAlive = await processIsAlive(lease.pid);
    if (typeof processAlive !== "boolean") {
      throw new RunStoreError(
        "Run-store process liveness check returned an invalid result.",
        { code: "ERR_INVALID_RUN_STORE_OPTIONS" },
      );
    }
    return processAlive;
  }

  async function leaseIsStale(lease) {
    const age = currentDate().valueOf() - Date.parse(lease.acquiredAt);
    if (age < staleMs || lease.hostname !== hostName) {
      return false;
    }
    return !(await ownerProcessIsAlive(lease));
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

  function createLeaseRecord(runId) {
    const token = tokenFactory();
    assertRunId(token);
    return {
      runId,
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
    const record = createLeaseRecord(runId);
    await writeLeaseFile(join(runDirectory, LEASE_FILENAME), record);
    return createLeaseHandle(runDirectory, record);
  }

  async function removeOwnedMarker(runDirectory, runId, token) {
    const markerPath = join(runDirectory, RECLAIMING_LEASE_FILENAME);
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
    const markerPath = join(runDirectory, RECLAIMING_LEASE_FILENAME);
    const marker = await readManagedLease(
      markerPath,
      runId,
      reclaimingLeaseDescription,
    );
    if (marker === null) {
      return;
    }
    if (!(await leaseIsStale(marker))) {
      throw new RunStoreError(
        `${leaseSubject(runId)} lease recovery is active.`,
        { code: conflictCode },
      );
    }
    await removeOwnedMarker(runDirectory, runId, marker.token);
  }

  async function acquire(runDirectory, runId) {
    const leasePath = join(runDirectory, LEASE_FILENAME);
    const markerPath = join(runDirectory, RECLAIMING_LEASE_FILENAME);

    for (let attempt = 0; attempt < 5; attempt += 1) {
      await clearRecoverableMarker(runDirectory, runId);
      try {
        return await createLeaseFile(runDirectory, runId);
      } catch (cause) {
        if (cause?.code !== "EEXIST") {
          throw cause;
        }
      }

      const existingLease = await readManagedLease(leasePath, runId);
      if (existingLease === null) {
        continue;
      }
      if (!(await leaseIsStale(existingLease))) {
        throw new RunStoreError(`${leaseSubject(runId)} is already leased.`, {
          code: conflictCode,
        });
      }

      const reclaimingLease = createLeaseRecord(runId);
      try {
        await writeLeaseFile(markerPath, reclaimingLease);
      } catch (cause) {
        if (cause?.code === "EEXIST") {
          continue;
        }
        throw cause;
      }

      const currentLease = await readManagedLease(leasePath, runId);
      if (currentLease?.token !== existingLease.token) {
        await removeOwnedMarker(runDirectory, runId, reclaimingLease.token);
        continue;
      }

      try {
        await removeFile(leasePath);
        await removeOwnedMarker(runDirectory, runId, reclaimingLease.token);
        return await createLeaseFile(runDirectory, runId);
      } catch (cause) {
        await removeOwnedMarker(runDirectory, runId, reclaimingLease.token);
        if (cause?.code === "EEXIST") {
          throw new RunStoreError(`${leaseSubject(runId)} is already leased.`, {
            cause,
            code: conflictCode,
          });
        }
        throw cause;
      }
    }

    throw new RunStoreError(
      `${leaseSubject(runId)} lease could not be acquired.`,
      { code: conflictCode },
    );
  }

  async function owner(runDirectory, runId) {
    const lease = await readManagedLease(
      join(runDirectory, LEASE_FILENAME),
      runId,
    );
    return lease !== null && !(await leaseIsStale(lease)) ? lease.runId : null;
  }

  async function isLeased(runDirectory, runId) {
    return (await owner(runDirectory, runId)) !== null;
  }

  async function ownerIsLive(runDirectory, runId) {
    const lease = await readManagedLease(
      join(runDirectory, LEASE_FILENAME),
      runId,
    );
    return (
      lease !== null &&
      (lease.hostname !== hostName || (await ownerProcessIsAlive(lease)))
    );
  }

  async function assertLeaseFile(metadata) {
    const persistedLease = await readManagedLease(
      join(metadata.runDirectory, LEASE_FILENAME),
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
      await assertLeaseFile(metadata);
      return await operation(metadata);
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

    await assertLeaseFile(metadata);
    await removeFile(join(metadata.runDirectory, LEASE_FILENAME));
    metadata.released = true;
  }

  return Object.freeze({ acquire, isLeased, owner, ownerIsLive, runExclusive });
}
