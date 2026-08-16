import { join } from "node:path";

import {
  createExclusiveFile,
  readOptionalText,
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

function parseJson(source, description) {
  try {
    return JSON.parse(source);
  } catch (cause) {
    throw new RunStoreError(`${description} contains invalid JSON.`, {
      cause,
      code: "ERR_INVALID_RUN_LEASE",
    });
  }
}

function parseLease(source, runId, description) {
  const value = parseJson(source, description);
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new RunStoreError(`${description} must be an object.`, {
      code: "ERR_INVALID_RUN_LEASE",
    });
  }
  const unknownField = Object.keys(value).find(
    (field) => !LEASE_FIELDS.has(field),
  );
  if (unknownField !== undefined) {
    throw new RunStoreError(`lease.${unknownField} is not supported.`, {
      code: "ERR_INVALID_RUN_LEASE",
    });
  }

  try {
    assertRunId(value.runId);
    assertRunId(value.token);
  } catch (cause) {
    throw new RunStoreError(`${description} identity is invalid.`, {
      cause,
      code: "ERR_INVALID_RUN_LEASE",
    });
  }
  const acquiredAt = new Date(value.acquiredAt);
  if (
    value.runId !== runId ||
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
      code: "ERR_INVALID_RUN_LEASE",
    });
  }

  return value;
}

async function readLease(filePath, runId, description = "Run lease") {
  const source = await readOptionalText(filePath);
  return source === null ? null : parseLease(source, runId, description);
}

export function createLeaseManager({
  currentDate,
  hostName,
  processId,
  processIsAlive,
  staleMs,
  timestamp,
  tokenFactory,
}) {
  const activeLeases = new WeakMap();

  async function leaseIsStale(lease) {
    const age = currentDate().valueOf() - Date.parse(lease.acquiredAt);
    if (age < staleMs || lease.hostname !== hostName) {
      return false;
    }
    const processAlive = await processIsAlive(lease.pid);
    if (typeof processAlive !== "boolean") {
      throw new RunStoreError(
        "Run-store process liveness check returned an invalid result.",
        { code: "ERR_INVALID_RUN_STORE_OPTIONS" },
      );
    }
    return !processAlive;
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
    await createExclusiveFile(filePath, `${JSON.stringify(record)}\n`);
  }

  async function createLeaseFile(runDirectory, runId) {
    const record = createLeaseRecord(runId);
    await writeLeaseFile(join(runDirectory, LEASE_FILENAME), record);
    return createLeaseHandle(runDirectory, record);
  }

  async function removeOwnedMarker(runDirectory, runId, token) {
    const markerPath = join(runDirectory, RECLAIMING_LEASE_FILENAME);
    const marker = await readLease(markerPath, runId, "Reclaiming lease");
    if (marker?.token === token) {
      await removeFile(markerPath);
    }
  }

  async function clearRecoverableMarker(runDirectory, runId) {
    const markerPath = join(runDirectory, RECLAIMING_LEASE_FILENAME);
    const marker = await readLease(markerPath, runId, "Reclaiming lease");
    if (marker === null) {
      return;
    }
    if (!(await leaseIsStale(marker))) {
      throw new RunStoreError(`Run ${runId} lease recovery is active.`, {
        code: "ERR_RUN_LEASED",
      });
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

      const existingLease = await readLease(leasePath, runId);
      if (existingLease === null) {
        continue;
      }
      if (!(await leaseIsStale(existingLease))) {
        throw new RunStoreError(`Run ${runId} is already leased.`, {
          code: "ERR_RUN_LEASED",
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

      const currentLease = await readLease(leasePath, runId);
      if (currentLease?.token !== existingLease.token) {
        await removeOwnedMarker(
          runDirectory,
          runId,
          reclaimingLease.token,
        );
        continue;
      }

      try {
        await removeFile(leasePath);
        await removeOwnedMarker(
          runDirectory,
          runId,
          reclaimingLease.token,
        );
        return await createLeaseFile(runDirectory, runId);
      } catch (cause) {
        await removeOwnedMarker(
          runDirectory,
          runId,
          reclaimingLease.token,
        );
        if (cause?.code === "EEXIST") {
          throw new RunStoreError(`Run ${runId} is already leased.`, {
            cause,
            code: "ERR_RUN_LEASED",
          });
        }
        throw cause;
      }
    }

    throw new RunStoreError(`Run ${runId} lease could not be acquired.`, {
      code: "ERR_RUN_LEASED",
    });
  }

  async function assertLeaseFile(metadata) {
    const persistedLease = await readLease(
      join(metadata.runDirectory, LEASE_FILENAME),
      metadata.record.runId,
    );
    if (persistedLease?.token !== metadata.record.token) {
      throw new RunStoreError("Execution lease is no longer owned.", {
        code: "ERR_INVALID_RUN_LEASE",
      });
    }
  }

  async function runExclusive(lease, operation) {
    const metadata = activeLeases.get(lease);
    if (metadata === undefined || metadata.released) {
      throw new RunStoreError("A current execution lease is required.", {
        code: "ERR_INVALID_RUN_LEASE",
      });
    }
    if (metadata.busy) {
      throw new RunStoreError("Execution lease already has an active write.", {
        code: "ERR_RUN_LEASE_BUSY",
      });
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
      throw new RunStoreError("Cannot release a busy execution lease.", {
        code: "ERR_RUN_LEASE_BUSY",
      });
    }

    await assertLeaseFile(metadata);
    await removeFile(join(metadata.runDirectory, LEASE_FILENAME));
    metadata.released = true;
  }

  return Object.freeze({ acquire, runExclusive });
}
